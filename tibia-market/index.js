require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');
const { Pool }  = require('pg');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const fetch     = require('node-fetch');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── DB ── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
});
const query = (t, p) => pool.query(t, p);
const transaction = async (fn) => {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const r = await fn(client); await client.query('COMMIT'); return r; }
  catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
};

/* ── TibiaData ── */
function normalizeVoc(v) {
  const m = {'Elite Knight':'Knight','Knight':'Knight','Royal Paladin':'Paladin','Paladin':'Paladin','Elder Druid':'Elder Druid','Druid':'Elder Druid','Master Sorcerer':'Master Sorcerer','Sorcerer':'Master Sorcerer','Monk':'Monk','None':'Sin vocación'};
  return m[v] || v;
}
async function getCharacter(name) {
  try {
    const r = await fetch(`https://api.tibiadata.com/v4/character/${encodeURIComponent(name)}`, { timeout: 10000 });
    if (r.status === 404) return null;
    if (!r.ok) return null;
    const d = await r.json();
    const c = d?.character?.character;
    if (!c?.name) return null;
    return { name: c.name, world: c.world, vocation: normalizeVoc(c.vocation), level: c.level || 1, guild: c.guild?.name || null };
  } catch { return null; }
}

/* ── Auth middleware ── */
async function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
    const payload = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    const { rows } = await query(
      `SELECT s.user_id,s.character_id,c.name AS cn,c.world,c.vocation,c.level,u.reputation,u.total_trades
       FROM sessions s JOIN characters c ON c.id=s.character_id JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.is_active=TRUE`, [payload.tokenHash]
    );
    if (!rows.length) return res.status(401).json({ error: 'Sesión inválida' });
    const s = rows[0];
    req.user = { id: s.user_id, reputation: s.reputation };
    req.character = { id: s.character_id, name: s.cn, world: s.world, vocation: s.vocation, level: s.level };
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}

/* ── Express setup ── */
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));
const limiter     = rateLimit({ windowMs: 15*60*1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 15 });
app.use(limiter);

/* ════ RUTAS AUTH ════ */
app.post('/api/auth/verify', authLimiter, async (req, res) => {
  const name = (req.body.characterName || '').trim();
  if (!name) return res.status(400).json({ error: 'Falta characterName' });
  const char = await getCharacter(name);
  if (!char) return res.status(404).json({ error: 'Personaje no encontrado en Tibia' });
  const { rows } = await query('SELECT user_id FROM characters WHERE name_lower=$1', [char.name.toLowerCase()]);
  res.json({ character: char, hasAccount: rows.length > 0 });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = (req.body.characterName || '').trim();
    const char = await getCharacter(name);
    if (!char) return res.status(404).json({ error: 'Personaje no encontrado' });
    const dup = await query('SELECT id FROM characters WHERE name_lower=$1', [char.name.toLowerCase()]);
    if (dup.rows.length) return res.status(409).json({ error: 'Este personaje ya tiene cuenta' });
    const result = await transaction(async (c) => {
      const { rows:[u] } = await c.query('INSERT INTO users DEFAULT VALUES RETURNING id');
      const { rows:[ch] } = await c.query(
        `INSERT INTO characters(user_id,name,name_lower,world,vocation,level,guild,is_primary)
         VALUES($1,$2,$3,$4,$5,$6,$7,TRUE) RETURNING id,name,world,vocation,level`,
        [u.id,char.name,char.name.toLowerCase(),char.world,char.vocation,char.level,char.guild]
      );
      const hash = crypto.randomBytes(32).toString('hex');
      const token = jwt.sign({ userId:u.id, characterId:ch.id, tokenHash:hash }, process.env.JWT_SECRET, { expiresIn:'30d' });
      await c.query('INSERT INTO sessions(user_id,character_id,token_hash,expires_at) VALUES($1,$2,$3,$4)',
        [u.id,ch.id,hash,new Date(Date.now()+30*24*60*60*1000)]);
      return { token, character:ch, userId:u.id };
    });
    res.status(201).json({ message:'¡Cuenta creada!', token:result.token, user:{ id:result.userId, character:result.character } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const name = (req.body.characterName || '').trim();
    const { rows } = await query(
      `SELECT c.id AS cid,c.user_id,c.name,c.world,c.vocation,c.level,u.is_active
       FROM characters c JOIN users u ON u.id=c.user_id WHERE c.name_lower=$1`, [name.toLowerCase()]
    );
    if (!rows.length) return res.status(404).json({ error: 'No existe cuenta para este personaje' });
    if (!rows[0].is_active) return res.status(403).json({ error: 'Cuenta suspendida' });
    const char = await getCharacter(name);
    if (!char) return res.status(404).json({ error: 'Personaje no encontrado en Tibia' });
    await query('UPDATE characters SET level=$1,last_sync=NOW() WHERE id=$2',[char.level,rows[0].cid]);
    const hash = crypto.randomBytes(32).toString('hex');
    const token = jwt.sign({ userId:rows[0].user_id, characterId:rows[0].cid, tokenHash:hash }, process.env.JWT_SECRET, { expiresIn:'30d' });
    await query('INSERT INTO sessions(user_id,character_id,token_hash,expires_at) VALUES($1,$2,$3,$4)',
      [rows[0].user_id,rows[0].cid,hash,new Date(Date.now()+30*24*60*60*1000)]);
    res.json({ token, user:{ id:rows[0].user_id, character:{ id:rows[0].cid, name:char.name, world:char.world, vocation:char.vocation, level:char.level } } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { rows } = await query('SELECT id,name,world,vocation,level,guild,is_primary FROM characters WHERE user_id=$1 ORDER BY is_primary DESC',[req.user.id]);
  res.json({ user:req.user, characters:rows, activeCharacter:req.character });
});

/* ════ RUTAS LISTINGS ════ */
app.get('/api/listings', async (req, res) => {
  try {
    const { server, category, search, page=1, limit=30 } = req.query;
    const where=[`il.status='active'`,`il.expires_at>NOW()`], params=[];
    if (server)   { params.push(server);       where.push(`il.server=$${params.length}`); }
    if (category) { params.push(category);     where.push(`il.item_category=$${params.length}`); }
    if (search)   { params.push(`%${search}%`);where.push(`il.item_name ILIKE $${params.length}`); }
    const offset=(Math.max(1,+page)-1)*Math.min(50,+limit), take=Math.min(50,+limit), ws=where.join(' AND ');
    const { rows } = await query(
      `SELECT il.*,c.name AS seller_name,c.world AS seller_world,c.vocation AS seller_voc,c.level AS seller_level,u.reputation AS seller_rep
       FROM item_listings il JOIN characters c ON c.id=il.character_id JOIN users u ON u.id=c.user_id
       WHERE ${ws} ORDER BY il.created_at DESC LIMIT ${take} OFFSET ${offset}`, params
    );
    res.json({ listings:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/listings', requireAuth, async (req, res) => {
  try {
    const { itemName,itemCategory,itemType,itemLevel=0,itemAtk,itemDef,itemArm,itemTier=0,itemVocation='Todos',price,negotiable=false,server,description,images=[] } = req.body;
    if (!itemName||!price||!server) return res.status(400).json({ error:'Faltan campos' });
    const { rows:[l] } = await query(
      `INSERT INTO item_listings(character_id,item_name,item_category,item_type,item_level,item_atk,item_def,item_arm,item_tier,item_vocation,price,negotiable,server,description,images)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id,item_name,price,server`,
      [req.character.id,itemName,itemCategory||'Otros',itemType||'',+itemLevel,itemAtk||null,itemDef||null,itemArm||null,+itemTier,itemVocation,+price,negotiable,server,description||null,images]
    );
    res.status(201).json({ message:'¡Item publicado!', listing:l });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/listings/my/active', requireAuth, async (req, res) => {
  const { rows } = await query(`SELECT id,item_name,item_category,price,server,negotiable,views,status,expires_at FROM item_listings WHERE character_id=$1 ORDER BY created_at DESC`,[req.character.id]);
  res.json({ listings:rows });
});

app.delete('/api/listings/:id', requireAuth, async (req, res) => {
  const { rowCount } = await query(`UPDATE item_listings SET status='deleted',updated_at=NOW() WHERE id=$1 AND character_id=$2`,[req.params.id,req.character.id]);
  if (!rowCount) return res.status(404).json({ error:'No encontrado' });
  res.json({ message:'Eliminado' });
});

/* ════ RUTAS TC ════ */
const FX = { MXN:17.2, USD:1, BRL:5.75 };
app.get('/api/tc', async (req, res) => {
  try {
    const { server, currency='MXN', page=1, limit=20 } = req.query;
    const where=[`tl.status='active'`,`tl.expires_at>NOW()`], params=[];
    if (server) { params.push(server); where.push(`tl.server=$${params.length}`); }
    const rate=FX[currency]||1, take=Math.min(50,+limit), offset=(Math.max(1,+page)-1)*take, ws=where.join(' AND ');
    const { rows } = await query(
      `SELECT tl.*,ROUND((tl.price_usd*$${params.length+1})::numeric,4) AS price_local,
       c.name AS seller_name,c.vocation AS seller_voc,c.level AS seller_level,u.reputation AS seller_rep
       FROM tc_listings tl JOIN characters c ON c.id=tl.character_id JOIN users u ON u.id=c.user_id
       WHERE ${ws} ORDER BY tl.price_usd ASC LIMIT ${take} OFFSET ${offset}`, [...params,rate]
    );
    res.json({ listings:rows, currency, rate });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/tc', requireAuth, async (req, res) => {
  try {
    const { amount,priceLocal,currency='MXN',server,minBuy=1,negotiable=false,notes } = req.body;
    if (!amount||!priceLocal||!server) return res.status(400).json({ error:'Faltan campos' });
    const priceUSD=parseFloat(priceLocal)/(FX[currency]||1);
    const { rows:[l] } = await query(
      `INSERT INTO tc_listings(character_id,amount,price_usd,currency,price_local,min_buy,server,negotiable,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,amount,price_usd`,
      [req.character.id,+amount,priceUSD,currency,+priceLocal,+minBuy,server,negotiable,notes||null]
    );
    res.status(201).json({ message:'¡TC publicado!', listing:l });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

/* ════ RUTAS MENSAJES ════ */
app.get('/api/messages', requireAuth, async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT cv.id,cv.last_message,cv.last_message_at,
       CASE WHEN cv.char_a_id=$1 THEN cv.unread_a ELSE cv.unread_b END AS unread,
       CASE WHEN cv.char_a_id=$1 THEN cb.name ELSE ca.name END AS other_name,
       COALESCE(il.item_name,'Tibia Coins') AS listing_name
       FROM conversations cv JOIN characters ca ON ca.id=cv.char_a_id JOIN characters cb ON cb.id=cv.char_b_id
       LEFT JOIN item_listings il ON il.id=cv.item_listing_id
       WHERE cv.char_a_id=$1 OR cv.char_b_id=$1 ORDER BY cv.last_message_at DESC NULLS LAST`, [req.character.id]
    );
    res.json({ conversations:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { recipientName, content, itemListingId } = req.body;
    if (!recipientName||!content) return res.status(400).json({ error:'Faltan campos' });
    const { rows:[recipient] } = await query('SELECT id FROM characters WHERE name_lower=$1',[recipientName.toLowerCase()]);
    if (!recipient) return res.status(404).json({ error:'Destinatario no encontrado' });
    const result = await transaction(async (c) => {
      const { rows:[ex] } = await c.query(
        `SELECT id FROM conversations WHERE ((char_a_id=$1 AND char_b_id=$2) OR (char_a_id=$2 AND char_b_id=$1)) LIMIT 1`,
        [req.character.id,recipient.id]
      );
      const cid = ex ? ex.id : (await c.query(
        `INSERT INTO conversations(char_a_id,char_b_id,item_listing_id) VALUES($1,$2,$3) RETURNING id`,
        [req.character.id,recipient.id,itemListingId||null]
      )).rows[0].id;
      const { rows:[msg] } = await c.query('INSERT INTO messages(conversation_id,sender_id,content) VALUES($1,$2,$3) RETURNING id,content,created_at',[cid,req.character.id,content]);
      const uf = ex?.char_a_id===recipient.id?'unread_a':'unread_b';
      await c.query(`UPDATE conversations SET last_message=$1,last_message_at=NOW(),${uf}=${uf}+1 WHERE id=$2`,[content.substring(0,100),cid]);
      return { msg, cid };
    });
    res.status(201).json({ message:result.msg, conversationId:result.cid });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

/* ════ PERSONAJES ════ */
app.get('/api/characters', requireAuth, async (req, res) => {
  const { rows } = await query('SELECT id,name,world,vocation,level,guild,is_primary FROM characters WHERE user_id=$1 ORDER BY is_primary DESC',[req.user.id]);
  res.json({ characters:rows });
});

app.post('/api/characters', requireAuth, async (req, res) => {
  try {
    const name=(req.body.characterName||'').trim();
    const char=await getCharacter(name);
    if (!char) return res.status(404).json({ error:'Personaje no encontrado' });
    const dup=await query('SELECT user_id FROM characters WHERE name_lower=$1',[char.name.toLowerCase()]);
    if (dup.rows.length) return res.status(409).json({ error:'Personaje ya registrado' });
    const { rows:[c] } = await query(
      `INSERT INTO characters(user_id,name,name_lower,world,vocation,level,guild,is_primary) VALUES($1,$2,$3,$4,$5,$6,$7,FALSE) RETURNING id,name,world,vocation,level`,
      [req.user.id,char.name,char.name.toLowerCase(),char.world,char.vocation,char.level,char.guild]
    );
    res.status(201).json({ message:`Personaje "${char.name}" agregado`, character:c });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

/* ════ HEALTH & ROOT ════ */
app.get('/',       (req, res) => res.json({ status:'ok' }));
app.get('/health', (req, res) => res.json({
  status:'ok', service:'Tibia Market API', version:'1.0.0',
  port:PORT, db: process.env.DATABASE_URL?'configurada':'falta'
}));

app.use((req, res) => res.status(404).json({ error:`Ruta no encontrada` }));
app.use((err, req, res, _n) => { console.error(err.message); res.status(err.status||500).json({ error:err.message }); });

app.listen(PORT, '0.0.0.0', () => console.log(`⚔️  Tibia Market API en puerto ${PORT}`));
module.exports = app;

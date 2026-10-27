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
const allowedOrigins = new Set(
  (process.env.CORS_ORIGINS || '').split(',').map(origin => origin.trim()).filter(Boolean)
);

/* ── DB ── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'disable' ? false : { rejectUnauthorized: true },
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
  let r;
  try {
    r = await fetch(`https://api.tibiadata.com/v4/character/${encodeURIComponent(name)}`, { timeout: 10000 });
  } catch(e) {
    throw new Error(`TibiaData no disponible: ${e.message}`);
  }
  let d;
  try {
    d = await r.json();
  } catch {
    throw new Error('TibiaData devolvió una respuesta inválida');
  }
  if (r.status === 404) return null;
  if (!r.ok) {
    const message=d?.information?.status?.message;
    throw new Error(`TibiaData respondió HTTP ${r.status}${message?`: ${message}`:''}`);
  }
  const c = d?.character?.character;
  if (!c?.name) return null;
  return {
    name: c.name,
    world: c.world,
    vocation: normalizeVoc(c.vocation),
    level: c.level || 1,
    guild: c.guild?.name || null,
    comment: typeof c.comment==='string' ? c.comment : '',
  };
}

function validCharacterProof(proofToken, character) {
  try {
    const proof=jwt.verify(proofToken,process.env.JWT_SECRET);
    return proof.scope==='character-ownership'&&
      proof.nameLower===character.name.toLowerCase()&&
      typeof proof.challenge==='string'&&
      character.comment.includes(proof.challenge);
  } catch {
    return false;
  }
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
    req.sessionHash = payload.tokenHash;
    req.user = { id: s.user_id, reputation: s.reputation };
    req.character = { id: s.character_id, name: s.cn, world: s.world, vocation: s.vocation, level: s.level };
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}

/* ── Express setup ── */
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));   // responde el preflight de TODAS las rutas
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));
const limiter     = rateLimit({ windowMs: 15*60*1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 15 });
app.use(limiter);

/* ════ RUTAS AUTH ════ */
app.post('/api/auth/verify', authLimiter, async (req, res) => {
  const name = typeof req.body?.characterName==='string' ? req.body.characterName.trim() : '';
  if (!name) return res.status(400).json({ error: 'Falta characterName' });
  try {
    const char = await getCharacter(name);
    if (!char) return res.status(404).json({ error: 'Personaje no encontrado en Tibia' });
    const { rows } = await query('SELECT user_id FROM characters WHERE name_lower=$1', [char.name.toLowerCase()]);
    res.json({
      character:{name:char.name,world:char.world,vocation:char.vocation,level:char.level,guild:char.guild},
      hasAccount:rows.length>0,
    });
  } catch(e) {
    console.error('POST /api/auth/verify:',e.message);
    res.status(e.message.startsWith('TibiaData')?502:500).json({ error:'No se pudo verificar el personaje. Intenta nuevamente en unos minutos.' });
  }
});

app.post('/api/auth/challenge', authLimiter, async (req, res) => {
  const name=typeof req.body?.characterName==='string'?req.body.characterName.trim():'';
  if (!name) return res.status(400).json({ error:'Falta characterName' });
  try {
    const character=await getCharacter(name);
    if (!character) return res.status(404).json({ error:'Personaje no encontrado en Tibia' });
    const challenge=`TIBIA-MARKET-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    const challengeToken=jwt.sign(
      { scope:'character-ownership',nameLower:character.name.toLowerCase(),challenge },
      process.env.JWT_SECRET,
      { expiresIn:'30m' }
    );
    res.json({
      character:{name:character.name,world:character.world,vocation:character.vocation,level:character.level},
      challenge,
      challengeToken,
      expiresIn:1800,
    });
  } catch(e) {
    console.error('POST /api/auth/challenge:',e.message);
    res.status(e.message.startsWith('TibiaData')?502:500).json({ error:'No se pudo consultar el personaje. Intenta nuevamente en unos minutos.' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = typeof req.body?.characterName==='string' ? req.body.characterName.trim() : '';
    if (!name) return res.status(400).json({ error:'Falta characterName' });
    const char = await getCharacter(name);
    if (!char) return res.status(404).json({ error: 'Personaje no encontrado' });
    if (!validCharacterProof(req.body?.proofToken,char)) {
      return res.status(403).json({ error:'Verifica primero el control del personaje desde su comentario público en Tibia' });
    }
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
  } catch(e) {
    if (e.code==='23505') return res.status(409).json({ error:'Este personaje ya tiene cuenta' });
    console.error('POST /api/auth/register:',e.message);
    res.status(e.message.startsWith('TibiaData')?502:500).json({ error:e.message.startsWith('TibiaData')?'No se pudo consultar TibiaData. Intenta nuevamente en unos minutos.':'No se pudo crear la cuenta' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const name = typeof req.body?.characterName==='string' ? req.body.characterName.trim() : '';
    if (!name) return res.status(400).json({ error:'Falta characterName' });
    const { rows } = await query(
      `SELECT c.id AS cid,c.user_id,c.name,c.world,c.vocation,c.level,u.is_active
       FROM characters c JOIN users u ON u.id=c.user_id WHERE c.name_lower=$1`, [name.toLowerCase()]
    );
    if (!rows.length) return res.status(404).json({ error: 'No existe cuenta para este personaje' });
    if (!rows[0].is_active) return res.status(403).json({ error: 'Cuenta suspendida' });
    const char = await getCharacter(name);
    if (!char) return res.status(404).json({ error: 'Personaje no encontrado en Tibia' });
    if (!validCharacterProof(req.body?.proofToken,char)) {
      return res.status(403).json({ error:'La prueba de control del personaje falta, expiró o ya no aparece en su comentario público' });
    }
    await query('UPDATE characters SET level=$1,last_sync=NOW() WHERE id=$2',[char.level,rows[0].cid]);
    const hash = crypto.randomBytes(32).toString('hex');
    const token = jwt.sign({ userId:rows[0].user_id, characterId:rows[0].cid, tokenHash:hash }, process.env.JWT_SECRET, { expiresIn:'30d' });
    await query('INSERT INTO sessions(user_id,character_id,token_hash,expires_at) VALUES($1,$2,$3,$4)',
      [rows[0].user_id,rows[0].cid,hash,new Date(Date.now()+30*24*60*60*1000)]);
    res.json({ token, user:{ id:rows[0].user_id, character:{ id:rows[0].cid, name:char.name, world:char.world, vocation:char.vocation, level:char.level } } });
  } catch(e) {
    console.error('POST /api/auth/login:',e.message);
    res.status(e.message.startsWith('TibiaData')?502:500).json({ error:e.message.startsWith('TibiaData')?'No se pudo consultar TibiaData. Intenta nuevamente en unos minutos.':'No se pudo iniciar sesión' });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await query('SELECT id,name,world,vocation,level,guild,is_primary FROM characters WHERE user_id=$1 ORDER BY is_primary DESC',[req.user.id]);
    res.json({ user:req.user, characters:rows, activeCharacter:req.character });
  } catch(e) {
    console.error('GET /api/auth/me:',e.message);
    res.status(500).json({ error:'No se pudo cargar la cuenta' });
  }
});

/* ════ RUTAS LISTINGS ════ */
function pagination(pageValue, limitValue, defaultLimit) {
  const requestedPage = Number.parseInt(pageValue,10);
  const requestedLimit = Number.parseInt(limitValue,10);
  const page = Number.isSafeInteger(requestedPage) && requestedPage>0 ? requestedPage : 1;
  const limit = Number.isSafeInteger(requestedLimit) ? Math.min(50,Math.max(1,requestedLimit)) : defaultLimit;
  return { limit, offset:(page-1)*limit };
}

app.get('/api/listings', async (req, res) => {
  try {
    const { server, category, search, page=1, limit=30 } = req.query;
    const where=[`il.status='active'`,`il.expires_at>NOW()`], params=[];
    if (server)   { params.push(server);       where.push(`il.server=$${params.length}`); }
    if (category) { params.push(category);     where.push(`il.item_category=$${params.length}`); }
    if (search)   { params.push(`%${search}%`);where.push(`il.item_name ILIKE $${params.length}`); }
    const {offset,limit:take}=pagination(page,limit,30);
    const ws=where.join(' AND ');
    const { rows } = await query(
      `SELECT il.*,c.name AS seller_name,c.world AS seller_world,c.vocation AS seller_voc,c.level AS seller_level,u.reputation AS seller_rep
       FROM item_listings il JOIN characters c ON c.id=il.character_id JOIN users u ON u.id=c.user_id
       WHERE ${ws} ORDER BY il.created_at DESC LIMIT ${take} OFFSET ${offset}`, params
    );
    res.json({ listings:rows });
  } catch(e) {
    console.error('POST /api/characters:',e.message);
    res.status(e.message.startsWith('TibiaData')?502:500).json({ error:e.message.startsWith('TibiaData')?'No se pudo consultar TibiaData. Intenta nuevamente en unos minutos.':'Error interno del servidor' });
  }
});

app.post('/api/listings', requireAuth, async (req, res) => {
  try {
    const { itemName,itemCategory,itemType,itemLevel=0,itemAtk,itemDef,itemArm,itemTier=0,itemVocation='Todos',price,negotiable=false,server,description,images=[] } = req.body||{};
    const parsedPrice=Number(price);
    if (typeof itemName!=='string'||!itemName.trim()||typeof server!=='string'||!server.trim()) {
      return res.status(400).json({ error:'Faltan campos' });
    }
    if (!Number.isSafeInteger(parsedPrice)||parsedPrice<=0) return res.status(400).json({ error:'El precio debe ser un entero positivo' });
    if (!Array.isArray(images)||images.length>4) return res.status(400).json({ error:'Se permiten hasta 4 imágenes' });
    if (typeof description==='string'&&description.length>2000) return res.status(400).json({ error:'La descripción supera el límite de 2000 caracteres' });
    const { rows:[l] } = await query(
      `INSERT INTO item_listings(character_id,item_name,item_category,item_type,item_level,item_atk,item_def,item_arm,item_tier,item_vocation,price,negotiable,server,description,images,status,expires_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'active',NOW()+INTERVAL '30 days') RETURNING id,item_name,price,server`,
      [req.character.id,itemName.trim(),itemCategory||'Otros',itemType||'',+itemLevel,itemAtk||null,itemDef||null,itemArm||null,+itemTier,itemVocation,parsedPrice,!!negotiable,server.trim(),description||null,JSON.stringify(images)]
    );
    res.status(201).json({ message:'¡Item publicado!', listing:l });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.get('/api/listings/my/active', requireAuth, async (req, res) => {
  try {
    const { rows } = await query(`SELECT id,item_name,item_category,price,server,negotiable,views,status,expires_at FROM item_listings WHERE character_id=$1 ORDER BY created_at DESC`,[req.character.id]);
    res.json({ listings:rows });
  } catch(e) {
    console.error('GET /api/listings/my/active:',e.message);
    res.status(500).json({ error:'No se pudieron cargar tus anuncios' });
  }
});

app.delete('/api/listings/:id', requireAuth, async (req, res) => {
  try {
    const { rowCount } = await query(`UPDATE item_listings SET status='deleted',updated_at=NOW() WHERE id=$1 AND character_id=$2`,[req.params.id,req.character.id]);
    if (!rowCount) return res.status(404).json({ error:'No encontrado' });
    res.json({ message:'Eliminado' });
  } catch(e) {
    console.error('DELETE /api/listings/:id:',e.message);
    res.status(500).json({ error:'No se pudo eliminar el anuncio' });
  }
});

/* ════ RUTAS TC ════ */
const FX = { MXN:17.2, USD:1, BRL:5.75 };
app.get('/api/tc', async (req, res) => {
  try {
    const { server, currency='MXN', page=1, limit=20 } = req.query;
    const where=[`tl.status='active'`,`tl.expires_at>NOW()`], params=[];
    if (server) { params.push(server); where.push(`tl.server=$${params.length}`); }
    if (!Object.prototype.hasOwnProperty.call(FX,currency)) return res.status(400).json({ error:'Moneda no soportada' });
    const rate=FX[currency], {offset,limit:take}=pagination(page,limit,20), ws=where.join(' AND ');
    const { rows } = await query(
      `SELECT tl.*,ROUND((tl.price_usd*$${params.length+1})::numeric,4) AS price_local,
       c.name AS seller_name,c.vocation AS seller_voc,c.level AS seller_level,u.reputation AS seller_rep
       FROM tc_listings tl JOIN characters c ON c.id=tl.character_id JOIN users u ON u.id=c.user_id
       WHERE ${ws} ORDER BY tl.price_usd ASC LIMIT ${take} OFFSET ${offset}`, [...params,rate]
    );
    res.json({ listings:rows, currency, rate });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.post('/api/tc', requireAuth, async (req, res) => {
  try {
    const { amount,priceLocal,currency='MXN',server,minBuy=1,negotiable=false,notes } = req.body||{};
    const parsedAmount=Number(amount), parsedPrice=Number(priceLocal), parsedMinBuy=Number(minBuy);
    if (!Number.isSafeInteger(parsedAmount)||parsedAmount<=0||!Number.isFinite(parsedPrice)||parsedPrice<=0||typeof server!=='string'||!server.trim()) {
      return res.status(400).json({ error:'Cantidad, precio o servidor inválido' });
    }
    if (!Object.prototype.hasOwnProperty.call(FX,currency)) return res.status(400).json({ error:'Moneda no soportada' });
    if (!Number.isSafeInteger(parsedMinBuy)||parsedMinBuy<1||parsedMinBuy>parsedAmount) return res.status(400).json({ error:'La compra mínima debe estar entre 1 y la cantidad publicada' });
    if (typeof notes==='string'&&notes.length>2000) return res.status(400).json({ error:'Las notas superan el límite de 2000 caracteres' });
    const priceUSD=parsedPrice/FX[currency];
    const { rows:[l] } = await query(
      `INSERT INTO tc_listings(character_id,amount,price_usd,currency,price_local,min_buy,server,negotiable,notes,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',NOW()+INTERVAL '30 days') RETURNING id,amount,price_usd`,
      [req.character.id,parsedAmount,priceUSD,currency,parsedPrice,parsedMinBuy,server.trim(),!!negotiable,notes||null]
    );
    res.status(201).json({ message:'¡TC publicado!', listing:l });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.delete('/api/tc/:id', requireAuth, async (req, res) => {
  try {
    const { rowCount } = await query(`UPDATE tc_listings SET status='deleted' WHERE id=$1 AND character_id=$2`,[req.params.id,req.character.id]);
    if (!rowCount) return res.status(404).json({ error:'No encontrado' });
    res.json({ message:'Eliminado' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
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
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.get('/api/messages/:id', requireAuth, async (req, res) => {
  const conversationId = Number(req.params.id);
  if (!Number.isSafeInteger(conversationId) || conversationId < 1) {
    return res.status(400).json({ error:'Conversación inválida' });
  }
  try {
    const messages = await transaction(async (c) => {
      const { rows:[conversation] } = await c.query(
        `SELECT id,char_a_id,char_b_id FROM conversations
         WHERE id=$1 AND (char_a_id=$2 OR char_b_id=$2) FOR UPDATE`,
        [conversationId,req.character.id]
      );
      if (!conversation) return null;
      const unreadColumn = conversation.char_a_id===req.character.id ? 'unread_a' : 'unread_b';
      await c.query(`UPDATE conversations SET ${unreadColumn}=0 WHERE id=$1`,[conversationId]);
      const { rows } = await c.query(
        `SELECT m.id,m.sender_id,ch.name AS sender_name,m.content,m.created_at
         FROM messages m JOIN characters ch ON ch.id=m.sender_id
         WHERE m.conversation_id=$1 ORDER BY m.created_at ASC,m.id ASC`,
        [conversationId]
      );
      return rows;
    });
    if (!messages) return res.status(404).json({ error:'Conversación no encontrada' });
    res.json({ messages });
  } catch(e) {
    console.error('GET /api/messages/:id:',e.message);
    res.status(500).json({ error:'No se pudo cargar la conversación' });
  }
});

app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { recipientName, content, itemListingId } = req.body||{};
    if (typeof recipientName!=='string'||!recipientName.trim()||typeof content!=='string'||!content.trim()) {
      return res.status(400).json({ error:'Faltan campos' });
    }
    const messageContent=content.trim();
    if (messageContent.length>2000) return res.status(400).json({ error:'El mensaje supera el límite de 2000 caracteres' });
    const { rows:[recipient] } = await query('SELECT id FROM characters WHERE name_lower=$1',[recipientName.trim().toLowerCase()]);
    if (!recipient) return res.status(404).json({ error:'Destinatario no encontrado' });
    if (recipient.id===req.character.id) return res.status(400).json({ error:'No puedes enviarte mensajes a ti mismo' });
    let linkedListingId=null;
    if (itemListingId!==undefined&&itemListingId!==null) {
      linkedListingId=Number(itemListingId);
      if (!Number.isSafeInteger(linkedListingId)||linkedListingId<1) return res.status(400).json({ error:'Anuncio inválido' });
      const { rows:[listing] } = await query(`SELECT id FROM item_listings WHERE id=$1 AND status='active' AND expires_at>NOW()`,[linkedListingId]);
      if (!listing) return res.status(404).json({ error:'Anuncio no encontrado' });
    }
    const result = await transaction(async (c) => {
      await c.query(
        'SELECT pg_advisory_xact_lock(hashtext(LEAST($1::text,$2::text)),hashtext(GREATEST($1::text,$2::text)))',
        [req.character.id,recipient.id]
      );
      const { rows:[ex] } = await c.query(
        `SELECT id,char_a_id FROM conversations WHERE ((char_a_id=$1 AND char_b_id=$2) OR (char_a_id=$2 AND char_b_id=$1)) ORDER BY id LIMIT 1 FOR UPDATE`,
        [req.character.id,recipient.id]
      );
      const cid = ex ? ex.id : (await c.query(
        `INSERT INTO conversations(char_a_id,char_b_id,item_listing_id) VALUES($1,$2,$3) RETURNING id`,
        [req.character.id,recipient.id,linkedListingId]
      )).rows[0].id;
      const { rows:[msg] } = await c.query('INSERT INTO messages(conversation_id,sender_id,content) VALUES($1,$2,$3) RETURNING id,content,created_at',[cid,req.character.id,messageContent]);
      const recipientIsA = ex ? ex.char_a_id===recipient.id : false;
      const unreadColumn = recipientIsA?'unread_a':'unread_b';
      await c.query(`UPDATE conversations SET last_message=$1,last_message_at=NOW(),${unreadColumn}=${unreadColumn}+1 WHERE id=$2`,[messageContent.substring(0,100),cid]);
      return { msg, cid };
    });
    res.status(201).json({ message:result.msg, conversationId:result.cid });
  } catch(e) {
    console.error('POST /api/messages:',e.message);
    res.status(500).json({ error:'No se pudo enviar el mensaje' });
  }
});

/* ════ PERSONAJES ════ */
app.get('/api/characters', requireAuth, async (req, res) => {
  const { rows } = await query('SELECT id,name,world,vocation,level,guild,is_primary FROM characters WHERE user_id=$1 ORDER BY is_primary DESC',[req.user.id]);
  res.json({ characters:rows });
});

app.post('/api/characters', requireAuth, async (req, res) => {
  try {
    const name=typeof req.body?.characterName==='string'?req.body.characterName.trim():'';
    if (!name) return res.status(400).json({ error:'Falta characterName' });
    const char=await getCharacter(name);
    if (!char) return res.status(404).json({ error:'Personaje no encontrado' });
    if (!validCharacterProof(req.body.proofToken,char)) {
      return res.status(403).json({ error:'Verifica primero el control del personaje desde su comentario público en Tibia' });
    }
    const dup=await query('SELECT user_id FROM characters WHERE name_lower=$1',[char.name.toLowerCase()]);
    if (dup.rows.length) return res.status(409).json({ error:'Personaje ya registrado' });
    const { rows:[c] } = await query(
      `INSERT INTO characters(user_id,name,name_lower,world,vocation,level,guild,is_primary) VALUES($1,$2,$3,$4,$5,$6,$7,FALSE) RETURNING id,name,world,vocation,level`,
      [req.user.id,char.name,char.name.toLowerCase(),char.world,char.vocation,char.level,char.guild]
    );
    res.status(201).json({ message:`Personaje "${char.name}" agregado`, character:c });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.patch('/api/characters/:id/primary', requireAuth, async (req, res) => {
  const characterId=Number(req.params.id);
  if (!Number.isSafeInteger(characterId)||characterId<1) return res.status(400).json({ error:'Personaje inválido' });
  try {
    const result=await transaction(async (client)=>{
      await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[req.user.id]);
      const { rows:[character] }=await client.query(
        `SELECT id,name,world,vocation,level,guild FROM characters
         WHERE id=$1 AND user_id=$2 FOR UPDATE`,
        [characterId,req.user.id]
      );
      if (!character) return null;
      await client.query('UPDATE characters SET is_primary=(id=$1) WHERE user_id=$2',[characterId,req.user.id]);
      const tokenHash=crypto.randomBytes(32).toString('hex');
      const token=jwt.sign(
        {userId:req.user.id,characterId:character.id,tokenHash},
        process.env.JWT_SECRET,
        {expiresIn:'30d'}
      );
      const sessionUpdate=await client.query(
        `UPDATE sessions SET character_id=$1,token_hash=$2,expires_at=$3
         WHERE token_hash=$4 AND user_id=$5`,
        [characterId,tokenHash,new Date(Date.now()+30*24*60*60*1000),req.sessionHash,req.user.id]
      );
      if (!sessionUpdate.rowCount) throw new Error('La sesión ya no existe');
      return {character,token};
    });
    if (!result) return res.status(404).json({ error:'Personaje no encontrado' });
    res.json(result);
  } catch(e) {
    console.error('PATCH /api/characters/:id/primary:',e.message);
    res.status(500).json({ error:'No se pudo cambiar el personaje principal' });
  }
});

app.delete('/api/characters/:id', requireAuth, async (req, res) => {
  const characterId=Number(req.params.id);
  if (!Number.isSafeInteger(characterId)||characterId<1) return res.status(400).json({ error:'Personaje inválido' });
  try {
    const result=await transaction(async (client)=>{
      const { rows:[character] }=await client.query(
        'SELECT id,is_primary FROM characters WHERE id=$1 AND user_id=$2 FOR UPDATE',
        [characterId,req.user.id]
      );
      if (!character) return 'missing';
      if (character.is_primary) return 'primary';
      const { rows:[usage] }=await client.query(
        `SELECT
          EXISTS(SELECT 1 FROM item_listings WHERE character_id=$1) OR
          EXISTS(SELECT 1 FROM tc_listings WHERE character_id=$1) OR
          EXISTS(SELECT 1 FROM char_listings WHERE character_id=$1) OR
          EXISTS(SELECT 1 FROM conversations WHERE char_a_id=$1 OR char_b_id=$1) AS in_use`,
        [characterId]
      );
      if (usage.in_use) return 'in-use';
      await client.query('DELETE FROM characters WHERE id=$1 AND user_id=$2',[characterId,req.user.id]);
      return 'deleted';
    });
    if (result==='missing') return res.status(404).json({ error:'Personaje no encontrado' });
    if (result==='primary') return res.status(409).json({ error:'Cambia el personaje principal antes de eliminar este personaje' });
    if (result==='in-use') return res.status(409).json({ error:'No se puede eliminar: el personaje tiene anuncios o conversaciones asociados y se debe conservar su historial' });
    res.json({ message:'Personaje eliminado' });
  } catch(e) {
    console.error('DELETE /api/characters/:id:',e.message);
    res.status(500).json({ error:'No se pudo eliminar el personaje' });
  }
});

/* ════ BAZAR DE PERSONAJES ════ */
app.get('/api/chars', async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT cl.*, c.name AS seller_name, u.reputation AS seller_rep, u.total_trades AS seller_trades
       FROM char_listings cl JOIN characters c ON c.id=cl.character_id JOIN users u ON u.id=c.user_id
       WHERE cl.status='active' AND cl.expires_at>NOW() ORDER BY cl.created_at DESC LIMIT 50`
    );
    res.json({ listings:rows });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.post('/api/chars', requireAuth, async (req, res) => {
  try {
    const { charName,vocation='Knight',level=0,world,price,bazaarLink,description,skills={},negotiable=false } = req.body||{};
    const parsedPrice=Number(price), parsedLevel=Number(level);
    let bazaarURL;
    try { bazaarURL=new URL(bazaarLink); } catch { bazaarURL=null; }
    if (typeof charName!=='string'||!charName.trim()||!Number.isSafeInteger(parsedPrice)||parsedPrice<=0||!bazaarURL||
      !['tibia.com','www.tibia.com'].includes(bazaarURL.hostname.toLowerCase())||!bazaarURL.pathname.startsWith('/charactertrade')) {
      return res.status(400).json({ error:'Personaje, precio o enlace del bazar inválido' });
    }
    if (!Number.isSafeInteger(parsedLevel)||parsedLevel<0) return res.status(400).json({ error:'Nivel inválido' });
    if (typeof description==='string'&&description.length>2000) return res.status(400).json({ error:'La descripción supera el límite de 2000 caracteres' });
    if (!skills||typeof skills!=='object'||Array.isArray(skills)) return res.status(400).json({ error:'Habilidades inválidas' });
    const { rows:[l] } = await query(
      `INSERT INTO char_listings(character_id,char_name,vocation,level,world,price,bazaar_link,description,skills,negotiable,status,expires_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'active',NOW()+INTERVAL '30 days') RETURNING id,char_name,price`,
      [req.character.id,charName.trim(),vocation,parsedLevel,world||null,parsedPrice,bazaarURL.toString(),description||null,JSON.stringify(skills),!!negotiable]
    );
    res.status(201).json({ message:'¡Personaje publicado!', listing:l });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

app.delete('/api/chars/:id', requireAuth, async (req, res) => {
  try {
    const { rowCount } = await query(`UPDATE char_listings SET status='deleted' WHERE id=$1 AND character_id=$2`,[req.params.id,req.character.id]);
    if (!rowCount) return res.status(404).json({ error:'No encontrado' });
    res.json({ message:'Eliminado' });
  } catch(e) { console.error(e); res.status(500).json({ error:'Error interno del servidor' }); }
});

/* ════ HEALTH & ROOT ════ */
app.get('/',       (req, res) => res.json({ status:'ok' }));
app.get('/health', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ status:'ok', service:'Tibia Market API', version:'1.0.0', port:PORT, db:'conectada' });
  } catch(e) {
    console.error('GET /health:',e.message);
    res.status(503).json({ status:'error', service:'Tibia Market API', db:'no disponible' });
  }
});

app.use((req, res) => res.status(404).json({ error:`Ruta no encontrada` }));
app.use((err, req, res, _n) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({ error:status<500 ? err.message : 'Error interno del servidor' });
});

async function initDb(){
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      reputation NUMERIC(8,2) NOT NULL DEFAULT 5,
      total_trades INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS characters (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      name_lower TEXT NOT NULL UNIQUE,
      world TEXT,
      vocation TEXT,
      level INTEGER NOT NULL DEFAULT 1,
      guild TEXT,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      last_sync TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      character_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS item_listings (
      id BIGSERIAL PRIMARY KEY,
      character_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      item_name TEXT NOT NULL,
      item_category TEXT NOT NULL DEFAULT 'Otros',
      item_type TEXT NOT NULL DEFAULT '',
      item_level INTEGER NOT NULL DEFAULT 0,
      item_atk INTEGER,
      item_def INTEGER,
      item_arm INTEGER,
      item_tier INTEGER NOT NULL DEFAULT 0,
      item_vocation TEXT NOT NULL DEFAULT 'Todos',
      price BIGINT NOT NULL CHECK (price > 0),
      negotiable BOOLEAN NOT NULL DEFAULT FALSE,
      server TEXT NOT NULL,
      description TEXT,
      images JSONB NOT NULL DEFAULT '[]'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      views INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
    )`,
    `CREATE TABLE IF NOT EXISTS tc_listings (
      id BIGSERIAL PRIMARY KEY,
      character_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      amount BIGINT NOT NULL CHECK (amount > 0),
      price_usd NUMERIC(14,4) NOT NULL CHECK (price_usd > 0),
      currency TEXT NOT NULL,
      price_local NUMERIC(14,4) NOT NULL CHECK (price_local > 0),
      min_buy BIGINT NOT NULL DEFAULT 1 CHECK (min_buy > 0),
      server TEXT NOT NULL,
      negotiable BOOLEAN NOT NULL DEFAULT FALSE,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
    )`,
    `CREATE TABLE IF NOT EXISTS char_listings (
      id SERIAL PRIMARY KEY,
      character_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      char_name TEXT NOT NULL,
      vocation TEXT,
      level INTEGER DEFAULT 0,
      world TEXT,
      price BIGINT DEFAULT 0,
      bazaar_link TEXT,
      description TEXT,
      skills JSONB DEFAULT '{}'::jsonb,
      negotiable BOOLEAN DEFAULT FALSE,
      status TEXT DEFAULT 'active',
      views INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days'
    )`,
    `CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      char_a_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      char_b_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      item_listing_id BIGINT REFERENCES item_listings(id) ON DELETE SET NULL,
      last_message TEXT,
      last_message_at TIMESTAMPTZ,
      unread_a INTEGER NOT NULL DEFAULT 0,
      unread_b INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (char_a_id <> char_b_id)
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id BIGINT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
      content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 2000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    'CREATE INDEX IF NOT EXISTS item_listings_active_idx ON item_listings(status,expires_at,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS tc_listings_active_idx ON tc_listings(status,expires_at,price_usd)',
    'CREATE INDEX IF NOT EXISTS char_listings_active_idx ON char_listings(status,expires_at,created_at DESC)',
    'CREATE INDEX IF NOT EXISTS sessions_user_expiry_idx ON sessions(user_id,expires_at)',
    'CREATE INDEX IF NOT EXISTS conversations_char_a_idx ON conversations(char_a_id,last_message_at DESC)',
    'CREATE INDEX IF NOT EXISTS conversations_char_b_idx ON conversations(char_b_id,last_message_at DESC)',
    'CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,created_at,id)',
    `CREATE TABLE IF NOT EXISTS app_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
  ];
  for (const statement of statements) {
    await query(statement);
  }
  await transaction(async (client)=>{
    const { rows }=await client.query(
      `INSERT INTO app_migrations(version) VALUES('character-ownership-proof-v1')
       ON CONFLICT(version) DO NOTHING RETURNING version`
    );
    if (rows.length) {
      await client.query('DELETE FROM sessions');
      console.log('✓ Sesiones anteriores revocadas para activar la verificación de propiedad');
    }
  });
  console.log('✓ Esquema de base de datos listo');
}

async function start(){
  if (!process.env.DATABASE_URL) throw new Error('Falta configurar DATABASE_URL');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length<32) {
    throw new Error('JWT_SECRET debe tener al menos 32 caracteres aleatorios');
  }
  await initDb();
  app.listen(PORT, '0.0.0.0', () => console.log(`⚔️  Tibia Market API en puerto ${PORT}`));
}

if (require.main===module) {
  start().catch(error=>{
    console.error('No se pudo iniciar Tibia Market API:',error.message);
    process.exitCode=1;
  });
}
module.exports = app;

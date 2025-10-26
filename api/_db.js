const { MongoClient, ObjectId } = require('mongodb');
let cached = global.mongo; if (!cached) cached = global.mongo = { conn: null, promise: null };
async function connect(){
  if (cached.conn) return cached.conn;
  if (!cached.promise){
    const uri = process.env.MONGODB_URI; if (!uri) throw new Error('Missing MONGODB_URI');
    const client = new MongoClient(uri);
    const dbName = process.env.MONGODB_DB || undefined;
    cached.promise = client.connect().then(client => ({ client, db: dbName ? client.db(dbName) : client.db() }));
  }
  cached.conn = await cached.promise; return cached.conn;
}
module.exports = { connect, ObjectId };

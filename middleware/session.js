// session.js
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export function verrifyToken(req,res,next){
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if(!token){
    return res.status(401).json({message : 'Missing token'});
  }

  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  }catch(err){
    return res.status(401).json({message : 'Invalid token'});
  }

}
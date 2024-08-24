const jwt = require('jsonwebtoken');
const User = require('../models/user');

const auth = async (req, res, next) =>{ 
    try{
        const token = req.header('Authorization').replace('Bearer ', '');
        const decode = jwt.verify(token , 'habib200')
        console.log(decode)

        const user = await User.findOne({_id:decode._id , tokens:token})
        if(!user){
            throw new Error('Unauthenticated')
        }
        req.user = user 
        req.token = token
        next()
    }
    catch(e){
        res.status(401).send({error: 'Unauthenticated'})
    }
}

module.exports = auth;
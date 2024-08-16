const jwt = require('jsonwebtoken');
const secret = "Fullstack-login-2024";

function checkRole(role){
    return function (req, res, next){
        try{
            if (!req.headers.authorization){
                return res.status(401).json({ status: 'error', message: 'No token provided'})
            }
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, secret);
            if (decoded.role === role){
                next();
            }else{
                res.status(403).json({ status: 'error', message:'Forbidden' });
            }

        }catch (err){
            res.status(401).json({ status: 'error', message: 'Unauthorized' })
        }
        

    };
}

module.exports = { checkRole };
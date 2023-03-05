const getDB = require('../db/getDB');
const { generateError } = require('../helpers');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const isAuth = async (req, res, next) => {
    let connection;

    try {
        //Conectamos con la bbdd
        connection = await getDB();

        const { authorization } = req.headers;

        if (!authorization) {
            throw generateError('Falta la autorizacion', 401);
        }

        let tokenInfo;

        try {
            //Desencriptar token
            console.log(authorization);
            tokenInfo = jwt.verify(authorization, process.env.SECRET);
        } catch (error) {
            throw generateError('Token no válido', 401);
        }

        //Comprobar que el id del usuario del token existe aún
        const [user] = await connection.query(
            `SELECT * FROM user WHERE id = ?`,
            [tokenInfo.id]
        );

        if (user.length < 1) {
            throw generateError('Token no válido', 401);
        }

        req.userAuth = tokenInfo;

        next();
    } catch (error) {
        next(error);
    } finally {
        //Cerramos conexión con la bbdd
        if (connection) connection.release();
    }
};

module.exports = isAuth;

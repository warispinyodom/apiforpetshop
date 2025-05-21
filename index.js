const express = require('express');
const cors = require('cors');
const knex = require('knex');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const secretKey = 'vzqhr';

const db = knex({
    client: 'mysql2',
    connection: {
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'petshop'
    }
});

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

app.get('/', async (req, res) => {
    console.log('this path /');
    res.json({ message: 'ข้อมูล server node.js'});
});

// function authorization
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'ไม่พบ token' });
    }

    try {
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded; // แนบข้อมูล user ไปใน req
        next(); // ผ่าน token ตรวจสอบแล้ว
    } catch (err) {
        res.status(403).json({ message: 'token ไม่ถูกต้องหรือหมดอายุ' });
    }
}

// test authorization
app.get('/testauthorization', verifyToken, (req, res) => {
  res.json({ message: 'เข้าถึงข้อมูลได้เพราะ token ผ่านแล้ว', user: req.user });
});


// การส่ง requese มา แบบ query params
app.get('/checkUser', async (req, res) => { 
    try {
        const { email, username } = req.query;

        // ทำการตรวจสอบฐานข้อมูล ห้ามมี user และ email ที่ซ้ำกัน
        const checkuser = await db('members') // ตาราง mermbers
        .select('m_email','m_user') // เลือก m_email และ m_user มาตรวจสอบ ข้อมูลที่ input request query เข้ามา
        .where({ m_email: email, // รับจาก ตัวแปรกำหนด req.query;
                m_user: username 
        });
        const exists = checkuser.length > 0; // หากมี checkuser นั้นมากกว่า 0 ก็คือมีฐานข้อมูลในนั้น 
        res.status(200).json({ exists }); // จะส่งกลับ ค่า boolean ที่เป็น true กลับไปยัง fontend
    } catch (err) {
        console.error(err);
    }
});

// การส่ง request มา insert ในแบบpost query ใน api
app.post('/register', async (req, res) => {

    try {
        const { username, email, password, tell } = req.body; //รับ request แบบ post ใช้ body request ในการส่ง forminput มา
        const default_status = "user"; // ค่าสถานะการใช้งาน

        if (!username || !email || !password || !tell) { // ตรวจสอบว่ามีการส่งข้อมูลมาจริง
            return res.status(400).json({ message: 'ข้อมูลไม่ครบ' });
        }

        const hash_password = await bcrypt.hash(password, saltRounds); // ทำการเข้ารหัส password

        // insert register data
        const register = await db('members')
        .insert({
            m_user: username,
            m_email: email,
            m_pass: hash_password,
            m_tell: tell,
            m_status: default_status
        });

        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ' }); // สถานะแจ้งเตือน แบบ json message ว่า     

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
    }

});

// ฟังชั่นในการเช็ค login ถ้า login ไม่มีในฐานข้อมูลจะให้ทำการตอบกลับไปว่า เข้าสู่ระบบไม่สำเร็จ
app.get('/login', async (req, res) => {

    try {

        const { email, password } = req.query;
        
        const checklogin = await db('members')
        .select('m_email', 'm_user', 'm_pass', 'm_tell', 'm_status')
        .where({
            m_email: email
        });

        // เช็คป้องกันค่า null
        if (checklogin.length === 0) {
            res.status(404).json({ messageg: 'ไม่มีข้อมูลในฐานข้อมูล' });
        }

        // เก็บ ข้อมูลฐานข้อมูล array 0 ไว้ดึง มาตรวจสอบ คล้าย fetch
        const user = checklogin[0];

        // decode jwt ฐานข้อมูลก่อน
        try {
            const match = await bcrypt.compare(password, user.m_pass);
            // console.log(match); // ดึงมาแสดงว่า decode ออกมาตรวจสอบ password ว่าถูกต้องตรงกันหรือไม่
            if (!match) {
                console.log('รหัสผ่านไม่ตรงกันกรุณาลองใหม่ครับ');
                res.send({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง!' })
            } else {
                
                // หากบัญชีตรงกันฐานข้อมูลจะใหัทำการ เก็บ token ไว้ที่ session หรือ localStorage หรือ cookie
                const token = jwt.sign(
                    {
                        username: user.m_user,
                        email: user.m_email,
                        status: user.m_status
                    },
                    secretKey,
                    { expiresIn: '1h' }
                );

                res.status(200).json({
                    message: 'เข้าสู่ระบบสำเร็จ',
                    token: token,
                    user: {
                        username: user.m_user,
                        email: user.m_email,
                        status: user.m_status
                    }
                });

            }
        } catch (err) {
            console.error(err);
        }

    } catch (err) {
        console.error(err);
    }

});

// api for register angular

// example api

// // ดึง user มาดู
// // สร้าง path api url และ ทำ async คำขอและ ตอบกลับ 
// app.get('/showuser', async (req, res) => {
//     // ลอง สร้าง showuser คือ รอ ดาตาเบส select ทั้งหมด จาก table members
//     try {
//         const showuser = await db.select('m_status').from('members').where({ m_email: 'dev@gmail.com'});
//         // ตอบกลับ json ผลลัพจาก showuser
//         res.json(showuser);
//     } catch (err) {
//         // สร้าง catch function err มาเก็บ err เพื่อจะ  console ออกมาเพื่อให้ consol.error แสดงเพื่อทราบสาเหตุ
//         console.error(err);
//         // ตอบกลับสถานะ 500  และ ส่ง stirng ไปว่า database error
//         res.status(500).send('Database error');
//     }
// });

// ตัวอย่างการเข้ารหัสด้วย jwt และ ถอดรหัส
// const payload = {
//     userId: 123,
//     username: 'testuser'
// };

// const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

// try {
//     const decoded = jwt.verify(token, secretKey);
//     console.log(decoded);
// } catch (err) {
//     console.log(err);
// }

app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});
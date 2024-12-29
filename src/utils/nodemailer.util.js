import { createTransport } from "nodemailer";
import envUtil from './env.util.js'
const { GOOGLE_EMAIL, GOOGLE_PASS } = envUtil

const transport = createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: GOOGLE_EMAIL, pass: GOOGLE_PASS }
})

const sendVerifyEmail = async ({ to, verifyCode }) => {
    try {
        await transport.verify()
        await transport.sendMail({
            from: GOOGLE_EMAIL,
            to,
            subject: 'Verify your account',
            html: `
                <p>Verify Code: ${verifyCode}</p>
            `
        })
    } catch (error) {
        throw error
    }
};

// Falta probar hacer!
const sendResetPassword = async () => {
    
}

export { sendVerifyEmail };
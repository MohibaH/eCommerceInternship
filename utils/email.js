
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const msg = {
  to: 'test@example.com', // Change to your recipient
  from: 'test@example.com', // Change to your verified sender
  subject: 'Sending with SendGrid is Fun',
  text: 'and easy to do anywhere, even with Node.js',
  html: '<strong>and easy to do anywhere, even with Node.js</strong>',
}

// exports.sendMail = async (options) => {
//   // 1- Create the transporter
//   sgMail.createTransport({
//     host: process.env.EMAIL_HOST,
//     port: process.env.EMAIL_PORT,
//     auth: {
//       //user: process.env.EMAIL_USERNAME,
//       //pass: process.env.EMAIL_PASSWORD,
//       user: process.env.SENDGRID_API_KEY,
//       pass: process.env.SENDGRID_API_KEY_PASSWORD,
//     },
//   });

//   // 2- Define the mail options:
//   const mailOptions = {
//     from: "Mohiba Hassan <mohiba42@gmail.com>",
//     to: options.email,
//     subject: options.subject,
//     text: options.message,
//   };

//   // 3- Send the mail
//   await transporter.sendMail(mailOptions);
// };
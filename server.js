const ex = require('express');
const app = ex();
const https = require('https');
const body = require('body-parser');
const mongoose = require('mongoose');
const alert = require('alert');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const saltRounds = 10;
app.set('view engine', 'ejs');
app.use(ex.static('css/'));
app.use(ex.static('public'));
app.use(ex.static('html/'));
app.use(ex.static('scripts/'));
app.use(ex.static('images/'));
app.use(cookieParser());
app.use(body.urlencoded({ extended: true }));
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER,
    pass: process.env.PASSWORD
  }
});
const url = "mongodb+srv://amar:amarnath123@cluster0.nely4hw.mongodb.net/?retryWrites=true&w=majority";
mongoose.connect(url, { useNewUrlParser: true });
const usersschema = new mongoose.Schema({
  name: String,
  phno: Number,
  email: String,
  Date: String,
  address: String,
  password: String,
  waterid: Number,
  form: Number,
  id: String
});
const emailschema = new mongoose.Schema({
  email: String
});
const billschema = new mongoose.Schema({
  Date: String,
  amount: Number,
  status: String,
  id: String
});
const otpschema = new mongoose.Schema({
  email: String,
  otp: Number,
  expiry: Date
});
const govschema = new mongoose.Schema({
  mailid: String,
  password: String
})
otpschema.index({ expiry: 1 }, { expireAfterSeconds: 300 });
const UserModel = mongoose.model('users', usersschema);
const GovModel = mongoose.model('govusers', govschema);
const MailModel = mongoose.model('subscribers', emailschema);
app.get('/', function (req, res) {
  const userEmail = req.cookies.userEmail;
  console.log(userEmail)
  if (userEmail) {
    return res.sendFile(__dirname + '/html/dashboard.html');
  } else {
    return res.sendFile(__dirname + '/html/index1.html');
  }
});
app.get('/govlogin/:email/:password', async (req, res) => {
  const email = req.params.email;
  const password = req.params.password;
  console.log('Received govlogin request with email:', email, 'and password:', password);
  
  try {
    const user = await GovModel.findOne({ email });

    if (user) {
      console.log('User found in the database:', user);
      if (user.password === password) {
        console.log('Password matches');
        return res.status(200).json({ success: true, message: 'Login successful' });
      } else {
        console.log('Password does not match');
        return res.status(400).json({ success: false, message: 'Incorrect password' });
      }
    } else {
      console.log('User not found');
      return res.status(400).json({ success: false, message: 'User does not exist' });
    }
  } catch (error) {
    console.error('Error querying the database:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


app.get('/otp/:email', async (req, res) => {
  const generatedOTP = Math.floor(1000 + Math.random() * 9000);
  const otpExpiry = new Date();
  otpExpiry.setMinutes(otpExpiry.getMinutes() + 5);
  const email = req.params.email;
  const OTPModel = mongoose.model('OTP', otpschema);
  const exist = await UserModel.findOne({ email })
  if (exist) {
    return res.status(400).json({ success: false, message: 'already user exists' });
  }
  const newOTP = new OTPModel({
    email: email,
    otp: generatedOTP,
    expiry: otpExpiry,
  });
  var mailOptions = {
    from: 'bodduamarnath2023@gmail.com',
    to: email,
    subject: 'otp for verfication',
    text: 'The otp for password request is:' + String(generatedOTP)
  };
  transporter.sendMail(mailOptions)
    .then(response => {
      alert('otp sent to mail');
    })
    .catch(error => {
      alert('please try again');
    });
  newOTP.save()
    .then(savedOTP => {
      res.json({ success: true });
    })
    .catch(error => {
      console.error('Error saving OTP:', error);
      res.status(500).json({ success: false, message: 'Failed to generate OTP.' });
    });
});

app.get('/validate/:email/:password/:otp', async (req, res) => {
  const email = req.params.email;
  const otp = req.params.otp;
  const password = req.params.password;
  console.log(req)
  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
  }
  try {
    const OTPModel = mongoose.model('OTP', otpschema);
    const existingOTP = await OTPModel.findOne({ email, otp });
    if (!existingOTP) {
      return res.status(400).json({ success: false, message: 'Invalid OTP or OTP expired.' });
    }
    const newUser = new UserModel({
      name: '',
      phno: null,
      email,
      Date: new Date(),
      address: '',
      password: password,
      waterid: 0,
      form: 0,
    });
    await newUser.save();
    res.cookie('userEmail', email, { httpOnly: true });

    return res.status(200).json({ success: true, message: 'User registered successfully.' });
  } catch (error) {
    console.error('Error validating OTP:', error);
    res.status(500).json({ success: false, message: 'Failed to validate OTP.' });
  }
});

app.get('/dashboard', (req, res) => {
  const userEmail = req.cookies.userEmail;
  console.log(userEmail)
  if (userEmail) {
    return res.sendFile(__dirname + '/html/dashboard.html');
  } else {
    res.redirect('/');
  }
});

app.get('/dashboard/:email', async (req, res) => {
  var email = req.params.email;
  var form = 1;
  try {
    const exist = await UserModel.findOne({ email, form }).exec();
    if (exist) {
      return res.redirect('/dashboard');
    } else {
      return res.sendFile(__dirname + '/html/form.html');
    }
  } catch (error) {
    console.error('Error querying the database:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/govdashboard', async (req, res) => {
  res.sendFile(__dirname + '/html/govdashboard.html');
});

app.get('/logout', (req, res) => {
  res.clearCookie('userEmail');
  res.redirect('/');
});

app.get('/gov', (req, res) => {
  res.sendFile(__dirname + '/html/logingov.html');
});
app.get('/login/:email/:password', async (req, res) => {
  const email = req.params.email;
  const password = req.params.password;
  try {
    const user = await UserModel.findOne({ email, password }).exec();

    if (!user) {
      const existingUser = await UserModel.findOne({ email }).exec();

      if (existingUser) {
        return res.status(400).json({ success: false, message: 'Incorrect password' });
      } else {
        return res.status(400).json({ success: false, message: 'User does not exist' });
      }
    }
    res.cookie('userEmail', email, { httpOnly: true, maxAge: 3600000 });
    return res.status(200).json({ success: true, message: 'Login successful' });
  } catch (error) {
    console.error('Error querying the database:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
app.get('/adddetails/:name/:id/:phno/:address', async (req, res) => {
  try {
    var name = req.params.name;
    var id = req.params.id;
    var phno = req.params.phno;
    var address = req.params.address;
    var id1 = req.cookies.userEmail;
    if (!id1) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }
    const user1 = await UserModel.updateOne({ email: id1 }, {
      name: name,
      waterid: id,
      phno: phno,
      address: address,
      form: 1
    });
    if (user1) {
      return res.status(200).json({ success: true, message: 'Successfully updated' });
    } else {
      return res.status(400).json({ success: false, message: 'Not updated' });
    }
  } catch (error) {
    console.error('Error updating user details:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
app.get('/fetch', async (req, res) => {
  const email = req.cookies.userEmail;
  if (email) {
    console.log(email)
    const existingUser = await UserModel.findOne({ email }).exec();
    console.log(existingUser)
    if (existingUser) {
      return res.status(200).json({ success: true, message: existingUser, email: email });
    }
    else {
      return res.status(400).json({ success: false, message: 'Not updated' });
    }
  } else {
    res.redirect('/');
  }
});
app.get('/subscribe/:email', async (req, res) => {
  try {
    var x = req.params.email;
    const new1 = new MailModel({
      email: x
    });
    await new1.save();
    console.log(new1);
    var mailOptions = {
      from: 'bodduamarnath2023@gmail.com',
      to: x,
      subject: 'Mail Conformation for Updates',
      text: 'Thank you for subscribing'
    };
    transporter.sendMail(mailOptions)
      .then(response => {
        console.log('email success');
      })
      .catch(error => {
        console.error('email failed:', error);
      });

    return res.status(200).json({ success: true, message: 'User registered successfully.' });
  }
  catch (error) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log('server is running successfully');
});
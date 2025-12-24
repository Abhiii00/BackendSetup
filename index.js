require('dotenv').config();
const express = require('express');
const connectDB = require('./src/config/dbConfig');
const route = require('./src/routes/route');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true })); 

app.use('/api', route);

app.get('/', (req, res) => {
  res.json('API is working');
});

const PORT = process.env.PORT || 4000;

connectDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to connect DB', err);
  });

const express = require('express');
const bodyParser = require('body-parser');
const cryptoRoutes = require('./routes/cryptoRoutes');

const app = express();
const port = 3000;

app.use(bodyParser.json()); // Para parsear cuerpos JSON de las peticiones
app.use('/api', cryptoRoutes); // Vinculamos las rutas con el prefijo "/api"

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

import serverless from 'serverless-http';
import app from '../server-app.mjs';

export default serverless(app);
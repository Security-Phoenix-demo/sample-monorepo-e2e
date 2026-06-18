const express = require('express');
const lodash = require('lodash');
const serialize = require('node-serialize');
const ejs = require('ejs');
const marked = require('marked');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// XSS: user input reflected into page without sanitization
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  res.send(`<html><body><h1>Results for: ${query}</h1></body></html>`);
});

// Prototype Pollution via lodash merge (CVE-2018-3721 — lodash < 4.17.5)
app.post('/merge', (req, res) => {
  const base = {};
  const merged = lodash.merge(base, req.body);
  res.json(merged);
});

// node-serialize RCE: deserializing untrusted cookie value
app.get('/profile', (req, res) => {
  const userData = req.cookies && req.cookies.user
    ? req.cookies.user
    : '{"username":"guest"}';
  // VULNERABLE: node-serialize.unserialize executes embedded JS functions
  const user = serialize.unserialize(userData);
  res.json(user);
});

// SSTI via EJS: user input injected into template string
app.get('/render', (req, res) => {
  const name = req.query.name || 'World';
  // VULNERABLE: user input in template — name=<%= process.env.SECRET %>
  ejs.render(`<h1>Hello <%= ${name} %></h1>`, {}, (err, html) => {
    if (err) return res.status(500).send(err.message);
    res.send(html);
  });
});

// XSS via marked (CVE-2022-21681 — marked < 4.0.10)
app.get('/docs', (req, res) => {
  const content = req.query.content || '# Welcome';
  // VULNERABLE: marked renders raw HTML without sanitization
  const html = marked(content);
  res.send(`<html><body>${html}</body></html>`);
});

// Path traversal: reads arbitrary files from disk
app.get('/static', (req, res) => {
  const file = req.query.file;
  // VULNERABLE: no path restriction — /static?file=../../etc/passwd
  const data = fs.readFileSync(path.join(__dirname, file), 'utf8');
  res.send(data);
});

// OS command injection via child_process.exec
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // VULNERABLE: shell=true + user input — /ping?host=google.com;id
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    res.send(stdout || stderr);
  });
});

// Open redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // VULNERABLE: no whitelist check on redirect target
  res.redirect(url);
});

app.listen(3000, () => console.log('Frontend listening on :3000'));

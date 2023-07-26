const express = require('express')

const PORT = 8082
const app = express()


app.get('/', (req, res) => {
    res.json({content: "hello world"})
})

app.listen(PORT, '0.0.0.0', () => console.log(`Running Express server on port ${PORT}`))
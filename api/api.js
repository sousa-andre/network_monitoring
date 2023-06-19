const express = require('express')

const PORT = 3001
const app = express()

console.log(`PID: ${process.pid}`)

app.get('/', (req, res) => {
    res.json({content: "hello world"})
})

app.listen(PORT, () => console.log(`running on port ${PORT}`))
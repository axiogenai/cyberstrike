export default function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.json({
        backendHost: process.env.BACKEND_URL || ''
    });
}

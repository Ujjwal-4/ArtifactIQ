from flask import Flask, render_template

app = Flask(__name__)

@app.get('/')
def index():
    return render_template('index.html')

@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'ArtifactIQ'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)

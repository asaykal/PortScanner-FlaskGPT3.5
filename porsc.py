from flask import Flask, render_template, request
import nmap, openai, yaml

app = Flask(__name__)

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

api_key = config["openai"]["api_key"]
openai.api_key = api_key

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    nm = nmap.PortScanner()
    results = nm.scan(hosts=target, arguments='-sS -sV -O -A')
    if results is None:
        return render_template('results.html')

    open_ports = []
    for port, info in results['scan'][target]['tcp'].items():
        if info['state'] == 'open':
            open_ports.append({
                'port': port,
                'name': info['name'],
                'product': info['product'],
                'version': info['version'],
                'extrainfo': info['extrainfo']
            })

    return render_template('results.html', open_ports=open_ports)

@app.route('/action', methods=['POST'])
def action():
    print(request.form)
    port = request.form['port']
    product = request.form['product']
    version = request.form['version']
    extra_info = request.form['extrainfo']
    print(port, product, version, extra_info)

    prompt = f"Generate information about this open port as a result of the scan {port} , {product} , {version} , {extra_info}."
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages = [
            {"role" : "system", "content" : "You are nmap professional you know everything about nmap port scanning and its resıults. You must give suggestions for vulneribilty of that port and suggestions for how to deal it etc... Guidance about if it is a good idea to close that port or not and how to close it or update it. "},
            {"role" : "user", "content" : f"{prompt}"},
            {"role" : "assistant", "content" : "Assistant : "}
        ],
        max_tokens=1024,
        n=1,
        stop=None,
        temperature=0.5,
    )
    if response:
        responses = response['choices'][0]['message']['content']
    else:
        responses = ["No information found."]
    return render_template('action.html', port=port, responses=responses, product=product, version=version, extra_info=extra_info)

if __name__ == '__main__':
    app.run(debug=True, port=8080)

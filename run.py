from app import create_app
from app.utils import generate_rsa_key_pair

app = create_app()

if __name__ == '__main__':
    generate_rsa_key_pair()
    app.run(debug=True, host='0.0.0.0', port=5000)


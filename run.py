from app import create_app
from app.config import Config
from app.utils import generate_rsa_key_pair

app = create_app()

if __name__ == '__main__':
    generate_rsa_key_pair()
    app.run(debug=True, host=Config.HOST, port=Config.PORT)

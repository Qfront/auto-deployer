from flask import Flask, request
import os
import hmac
import hashlib
import subprocess

app = Flask(__name__)

# BP: environment variable
webhook_secret = "some_secret_key" <-
main_repo_path = "/root/repo_name" <-


@app.route('/deploy', methods=['POST'])
def handle_deploy():
    # Попытка получить заголовок и проверить его подлинность
    try:
        signature = request.headers.get('X-Hub-Signature-256')
        if not is_valid_signature(request.data, signature):
            return 'Unauthorized', 401
    except Exception as e:
        return 'Bad Request', 400
    # Обновление основного репозитория
    os.chdir(main_repo_path)
    subprocess.call(['git', 'pull'])

    return 'Deployed successfully'


# Проверка подлинности подписи запроса
def is_valid_signature(data, signature):
    mac = hmac.new(bytes(webhook_secret, 'utf-8'), msg=data, digestmod=hashlib.sha256)
    expected_signature = 'sha256=' + mac.hexdigest()
    return hmac.compare_digest(signature, expected_signature)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=some_port) <-

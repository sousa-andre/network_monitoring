pipeline {
    agent any

    stages {
        stage("Dependencies update and installation") {
            steps {
                sh "apt update"
                sh "apt install -y python3"
                sh "apt install -y python3-pip"
            }
        }
        stage("Git checkout") {
            steps {
                checkout scm
            }
        }
        stage("Python dependencies installation") {
            steps {
                sh "pip install -r load/requirements.txt"
            }
        }
        stage("Run locust") {
            steps {
                sh "export DATABASE_HOST=abcd;export DATABASE_PORT=5432;export DATABASE_USERNAME=postgres; DATABASE_PASSWORD=postgres;locust --headless -f load/locustfiles/locustfile.py  --host http://nginx -u 200"
            }
        }
    }
}

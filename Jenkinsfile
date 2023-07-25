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
                withCredentials([usernamePassword(credentialsId: "database", usernameVariable: "DATABASE_USERNAME", passwordVariable: "DATABASE_PASSWORD")]) {
                    sh "locust --headless -f load/locustfiles/locustfile.py  --host http://nginx -u 200"
                }
            }
        }
    }
}

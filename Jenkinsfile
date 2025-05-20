#!/usr/bin/env groovy

pipeline {
    agent any
    
    stages {
        stage('Run Script') {
            steps {
                script {
                    sh "python3 main.py"
                }
            }
        }
    }
}
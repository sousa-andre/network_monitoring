FROM python:3.8.17-alpine
WORKDIR /app .
COPY . .
EXPOSE 8082
RUN pip install -r requirements.txt
CMD uvicorn main:app
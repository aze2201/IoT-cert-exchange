FROM kxiras/cryptography-python:latestx64 AS build
FROM python:3.9-slim
ENV PATH "$PATH:/home/onsite-cls/.local/bin"
USER root
COPY --from=build /usr/local/lib/python3.9/site-packages/ /usr/local/lib/python3.9/site-packages/
RUN pip install flask flask_cors Flask-OIDC pyOpenSSL itsdangerous==2.0.1
RUN mkdir /root/app
WORKDIR /root/app
COPY api/ /root/app/
CMD [ "flask", "run", "--host=0.0.0.0","--port","8081"]

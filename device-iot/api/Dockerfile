FROM kxiras/cryptography-python:latestx64 AS build
FROM python:3.9-slim
ENV PATH "$PATH:/home/onsite-cls/.local/bin"
USER root
COPY --from=build /usr/local/lib/python3.9/site-packages/ /usr/local/lib/python3.9/site-packages/
RUN pip install --user bottle pyOpenSSL
WORKDIR /root/
COPY api/main.py /root
CMD ["/root/main.py"]
ENTRYPOINT ["python"]

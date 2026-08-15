FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum install -y python3 openssl
ENV SIGNER_PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903
COPY . /app
CMD ["python3", "/app/server.py"]

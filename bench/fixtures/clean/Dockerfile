FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff
RUN yum install -y python3-3.9.16 openssl-3.0.8
COPY . /app
CMD ["python3", "/app/server.py"]

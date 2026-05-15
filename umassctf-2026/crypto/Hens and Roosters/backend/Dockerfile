FROM sagemath/sagemath:latest

USER root

RUN sage -pip install flask gunicorn redis[hiredis]

COPY app.py uov.py private_key.sobj public_key.sobj ./
EXPOSE 8000
CMD ["sage", "-python", "-m", "gunicorn", "app:app", "-k", "gthread", "--threads", "80", "-w", "1", "--bind", "0.0.0.0:8000"]

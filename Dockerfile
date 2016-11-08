FROM python:2.7
ADD . /foghorn
WORKDIR /foghorn
RUN pip install -r requirements.txt
CMD PYTHONPATH=. python foghorn.py


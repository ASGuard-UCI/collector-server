FROM ros:humble

RUN apt update && apt upgrade -y

RUN apt install libpcap0.8 libpcap0.8-dev libpcap-dev tcpdump -y python3 python3-pip

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./ /code/

RUN mkdir data

CMD ["python3", "main.py"]

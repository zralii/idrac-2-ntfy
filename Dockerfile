FROM python:3.12-slim

LABEL maintainer="idrac-2-ntfy"
LABEL description="SNMP trap receiver that forwards Dell iDRAC alerts to ntfy"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idrac_oids.py trap_receiver.py ./

# SNMP trap port
EXPOSE 162/udp

# Drop to non-root for the process itself — but we need NET_BIND_SERVICE
# for port 162. The compose file grants the capability.
RUN useradd --system --no-create-home trapuser
USER trapuser

ENTRYPOINT ["python", "-u", "trap_receiver.py"]

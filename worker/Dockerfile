FROM scratch as init
ADD . /app/

FROM alpine:3.20
RUN mkdir /app
COPY --from=init /app/ok /app/
COPY ./another-file /app/
WORKDIR /app

FROM golang:1.17.1

WORKDIR /istio-security-analyzer/

RUN apt install gcc

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY  . ./

RUN go build cmd/main.go

CMD [ "./main" ]



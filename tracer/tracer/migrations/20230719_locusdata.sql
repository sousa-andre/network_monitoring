create table locustdata
(
    id                   serial
        primary key,
    url                  varchar(255),
    timestamp            timestamp,
    request_count        integer,
    failure_count        integer,
    avg_response_time    integer,
    min_response_time    integer,
    max_response_time    integer,
    median_response_time double precision
);

alter table locustdata
    owner to postgres;


create table requests
(
    id                     serial
        primary key,
    method                 varchar not null,
    path                   varchar not null,
    body                   varchar,
    timestamp_seconds      bigint  not null,
    timestamp_nanoseconds  integer not null,
    read_delta_nanoseconds integer
);

alter table requests
    owner to postgres;

create table headers
(
    id         serial
        primary key,
    key        varchar not null,
    value      varchar not null,
    request_id integer
        references requests
);

alter table headers
    owner to postgres;


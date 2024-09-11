run this only if startup script is not working:

psql -U postrgres_user -d certstream_db

create table sus_domains (id SERIAL PRIMARY KEY, domain_name VARCHAR(255), score INT, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), issuer VARCHAR(255), check_domain boolean, suspicious boolean);

select * from sus_domains;
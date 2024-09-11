#!/bin/bash

# Create the table
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"<<-EOSQL
    -- Create the 'sus_domains' table
    CREATE TABLE IF NOT EXISTS sus_domains (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255),
        score INT,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        issuer VARCHAR(255),
        check_domain BOOLEAN,
        suspicious BOOLEAN
    );

    -- Optional: Add indexes for better performance (if needed)
    CREATE INDEX idx_domain_name ON sus_domains(domain_name);
EOSQL
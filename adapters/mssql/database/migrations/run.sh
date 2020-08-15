#!/bin/bash

# Before running migrate:
# create the database, schema and user
# export SQLSERVER="sqlserver://user:password@host:1433?database=RICKY&x-migrations-table=MigrationsTable"

source init.in
migrate -source file://$(pwd) -database $SQLSERVER up 

CREATE SEQUENCE defense_seq;

CREATE TABLE IF NOT EXISTS defense (
  id int NOT NULL DEFAULT NEXTVAL ('defense_seq'),
  epoch int NOT NULL,
  type smallint NOT NULL,
  ipaddr varchar(256) NOT NULL,
  data text NOT NULL,
  PRIMARY KEY (id)
)    ;
 
ALTER SEQUENCE defense_seq RESTART WITH 30;

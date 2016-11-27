import time
from peewee import *

db = SqliteDatabase('vulns.db')


class BaseModel(Model):

    class Meta:
        database = db


class Vulnerabilities(BaseModel):
    id = IntegerField(primary_key=True, unique=True)
    method = CharField()
    url = CharField()
    get_arguments = CharField(default="")
    post_arguments = CharField(default="")
    vector = CharField()
    payload_uri = CharField()
    created_date = CharField(default=time.strftime("%d-%m-%Y %H:%M"))

db.connect()
db.create_tables([Vulnerabilities], safe=True)

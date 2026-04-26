"""
WebGuard AI — Database Layer (In-Memory Mock)
"""
import logging
import asyncio

logger = logging.getLogger(__name__)

class MockCursor:
    def __init__(self, data):
        self.data = data
        self._sort = None
        self._skip = 0
        self._limit = None

    def sort(self, field, direction):
        self._sort = (field, direction)
        if field == "created_at":
            self.data.sort(key=lambda x: x.get(field, 0) if x.get(field) is not None else "", reverse=(direction == -1))
        return self

    def skip(self, skip):
        self._skip = skip
        return self

    def limit(self, limit):
        self._limit = limit
        return self

    async def to_list(self, length=None):
        d = self.data[self._skip:]
        lim = self._limit if self._limit is not None else length
        if lim is not None:
            d = d[:lim]
        return d

class MockCollection:
    def __init__(self):
        self.documents = []

    async def create_index(self, *args, **kwargs):
        pass

    async def insert_one(self, doc):
        self.documents.append(doc)
        return type('InsertOneResult', (), {'inserted_id': 'mock_id'})()

    async def find_one(self, query, projection=None):
        for doc in self.documents:
            match = True
            for k, v in query.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                if projection and "_id" in projection and projection["_id"] == 0:
                    ret = doc.copy()
                    ret.pop("_id", None)
                    return ret
                return doc.copy()
        return None

    async def update_one(self, query, update):
        op = update.get("$set", {})
        count = 0
        for doc in self.documents:
            match = True
            for k, v in query.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                doc.update(op)
                count = 1
                break
        return type('UpdateResult', (), {'modified_count': count})()

    async def delete_one(self, query):
        count = 0
        for i, doc in enumerate(self.documents):
            match = True
            for k, v in query.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                del self.documents[i]
                count = 1
                break
        return type('DeleteResult', (), {'deleted_count': count})()

    async def count_documents(self, query):
        return len(self.documents)

    def find(self, query, projection=None):
        results = []
        for doc in self.documents:
            match = True
            for k, v in query.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                if projection and "_id" in projection and projection["_id"] == 0:
                    ret = doc.copy()
                    ret.pop("_id", None)
                    results.append(ret)
                else:
                    results.append(doc.copy())
        return MockCursor(results)

class MockDB:
    def __init__(self):
        self.scans = MockCollection()

db = None

async def connect_db():
    global db
    db = MockDB()
    logger.info("Connected to In-Memory Mock database")

async def disconnect_db():
    global db
    db = None
    logger.info("Disconnected from In-Memory Mock database")

def get_db():
    return db

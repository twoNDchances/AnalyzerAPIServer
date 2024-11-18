from setup import es

es.indices.delete(index='analyzer-actions')

es.indices.delete(index='analyzer-action-timestamps')

es.indices.delete(index='analyzer-results')

es.indices.delete(index='analyzer-sqlis')

es.indices.delete(index='analyzer-xsss')

es.indices.delete(index='analyzer-fus')

es.indices.delete(index='analyzer-rules')

es.indices.delete(index='analyzer-yaras')
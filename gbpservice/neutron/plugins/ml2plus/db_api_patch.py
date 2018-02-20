class ContextManager(object):

    class Writer(object):

        def using(self, context):
            return context.session.begin(subtransactions=True)

    def __init__(self):
        self.writer = ContextManager.Writer()

context_manager = ContextManager()

//! One backend connection per client session.
//!
//! A client's `USE`, `SET`, `BEGIN`, temp tables and locks live on the backend
//! connection. Sharing pooled connections per statement leaked that state to
//! other clients and split transactions across connections. So a session pins
//! the connection it first checks out, and on session end the connection is
//! detached from the pool and closed, never handed to another client.
//!
//! ponytail: connect per session; reset-and-reuse (COM_RESET_CONNECTION /
//! DISCARD ALL) if backend connect latency ever matters.

use deadpool::managed::{Manager, Object, Pool, PoolError};

pub struct SessionConn<'a, M: Manager> {
    pool: &'a Pool<M>,
    conn: Option<Object<M>>,
}

impl<'a, M: Manager> SessionConn<'a, M> {
    pub fn new(pool: &'a Pool<M>) -> Self {
        Self { pool, conn: None }
    }

    /// The session's connection, checked out from the pool on first use.
    pub async fn get(&mut self) -> Result<&mut M::Type, PoolError<M::Error>> {
        if self.conn.is_none() {
            self.conn = Some(self.pool.get().await?);
        }
        Ok(self.conn.as_mut().expect("just set"))
    }

    pub fn manager(&self) -> &'a M {
        self.pool.manager()
    }

    /// The connection, if the session has checked one out yet.
    pub fn current(&mut self) -> Option<&mut M::Type> {
        self.conn.as_deref_mut()
    }
}

impl<M: Manager> Drop for SessionConn<'_, M> {
    fn drop(&mut self) {
        if let Some(obj) = self.conn.take() {
            drop(Object::take(obj));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool::managed::{Metrics, RecycleResult};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Counter(AtomicU32);

    impl Manager for Counter {
        type Type = u32;
        type Error = std::convert::Infallible;
        async fn create(&self) -> Result<u32, Self::Error> {
            Ok(self.0.fetch_add(1, Ordering::SeqCst))
        }
        async fn recycle(&self, _: &mut u32, _: &Metrics) -> RecycleResult<Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn session_reuses_its_conn_and_never_returns_it_to_the_pool() {
        let pool = Pool::builder(Counter(AtomicU32::new(0)))
            .max_size(1)
            .build()
            .unwrap();
        {
            let mut a = SessionConn::new(&pool);
            assert_eq!(*a.get().await.unwrap(), 0);
            assert_eq!(*a.get().await.unwrap(), 0, "same conn within a session");
        }
        // The slot is free again (max_size 1), and the next session gets a
        // brand-new connection, not session A's.
        let mut b = SessionConn::new(&pool);
        assert_eq!(*b.get().await.unwrap(), 1);
        assert_eq!(pool.status().size, 1);
    }
}

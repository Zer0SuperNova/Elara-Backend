import 'dotenv/config';

const config = {
    environment: process.env.ENVIRONMENT || 'dev',
    debug: true,
    db: {
        mysql: {
            host: process.env.MYSQL_HOST,
            dbname: process.env.MYSQL_DBNAME,
            user: process.env.MYSQL_USER,
            password: process.env.MYSQL_PASSWORD
        },
        redis: {
            host: process.env.REDIS_HOST,
            port: process.env.REDIS_PORT,
            username: process.env.REDIS_USERNAME,
            password: process.env.REDIS_PASSWORD
        },
        s3: {
            accessKey: process.env.S3_ACCESS_KEY,
            secretKey: process.env.S3_SECRET_KEY,
            host: process.env.S3_HOST,
            port: process.env.S3_PORT,
            useSSL: false,
        },
        clickhouse: {
            url: process.env.CLICKHOUSE_URL,
            username: process.env.CLICKHOUSE_USER,
            password: process.env.CLICKHOUSE_PASSWORD,
            database: process.env.CLICKHOUSE_DB
        }
    },
    endpoints: {
        api: {
            hostname: "0.0.0.0",
            port: "8081"
        }
    },
    serverKeys: {
        static: {
            core: {
                public: process.env.SERVER_STATIC_PUBLIC,
                secret: process.env.SERVER_STATIC_SECRET,
                psk: process.env.PSK
            },
            loader: {
                public: process.env.SERVER_STATIC_PUBLIC_Loader,
                secret: process.env.SERVER_STATIC_SECRET_Loader,
                psk: process.env.PSK_Loader
            }
        }
    }
};

export default config;

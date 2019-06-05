using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using SqlAzureKeyVaultProvider;
// Our custom CMK provider


namespace SqlKeyVaultSampleApp
{
    static class Program
    {
        static string _applicationClientId;
        static string _applicationKey;
        static string _connectionString;
        static string _keyId;
        static bool _runSetupOnly; 

        const string AppClientIdToken = @"-i";
        const string AppKey = @"-s";
        const string KeyId = @"-k";
        const string Token = @"-c";
        const string Operation = @"-o";
        const string OperationCreateKeyObjects = @"setup";
        const string OperationDataAccess = @"data_access";

        private const string CreateColumnEncryptionKeyTemplate = @"
            CREATE COLUMN ENCRYPTION KEY [{0}]
            WITH VALUES
              (
                COLUMN_MASTER_KEY = [{1}],
                ALGORITHM = 'RSA_OAEP',
                ENCRYPTED_VALUE = {2}
              );";

        private const string CreateColumnMasterKeyTemplate = @"
            CREATE COLUMN MASTER KEY [{0}] 
                WITH ( KEY_STORE_PROVIDER_NAME = '{1}', 
                KEY_PATH = '{2}');";

        private const string CreateTableTemplate = @"
            CREATE TABLE [dbo].[Test](
	            [PatientId] [int] IDENTITY(1,1) NOT NULL,
	            [SSN] [char](11) COLLATE Latin1_General_BIN2
                    ENCRYPTED WITH ( 
                        COLUMN_ENCRYPTION_KEY = [{0}], 
                        ENCRYPTION_TYPE = Deterministic, 
                        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
                    ) NOT NULL,
            PRIMARY KEY CLUSTERED 
            (
	            [PatientId] ASC
            )WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
            ) ON [PRIMARY]
            ;";

        private static async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_applicationClientId, _applicationKey);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        static string BytesToHex(byte[] data)
        {
            if (data == null)
            {
                return @"null";
            }

            StringBuilder strbld = new StringBuilder(2 + (data.Length * 2));
            strbld.Append("0x");

            for (int i = 0; i < data.Length; i++)
            {
                strbld.AppendFormat(@"{0:x2}", data[i]);
            }

            return strbld.ToString();
        }

        static void InsertData(SqlConnection connection, string ssn)
        {
            var cmd = connection.CreateCommand();

            cmd.CommandText = @"INSERT INTO [dbo].[Test] VALUES ( @ssn )";
            var paramSsn = cmd.CreateParameter();
            paramSsn.DbType = System.Data.DbType.AnsiStringFixedLength;
            paramSsn.Size = 11;
            paramSsn.Direction = System.Data.ParameterDirection.Input;
            paramSsn.ParameterName = @"@ssn";
            paramSsn.SqlValue = ssn;
            cmd.Parameters.Add(paramSsn);

            cmd.ExecuteNonQuery();
        }

        static void SelectData(SqlConnection connection)
        {
            var cmd = connection.CreateCommand();

            // Prevent SQL injections by escaping the user-defined tokens
            cmd.CommandText = @"SELECT * FROM [dbo].[Test]";

            var reader = cmd.ExecuteReader();
            if (reader.HasRows)
            {
                while (reader.Read())
                {
                    Console.WriteLine(@"{0}, {1}", reader[0], reader[1]);
                }
            }
        }

        [SuppressMessage("Microsoft.Security", "CA2100", Justification = "The SqlCommand text is issuing a DDL statement that requires to use only literals (no parameterization is possible). The user input is being escaped.", Scope = "method")]
        static void CreateColumnMasterKey(SqlConnection connection, string cmkName, string providerName, string keyId)
        {
            SqlCommand cmd = connection.CreateCommand();

            // Prevent SQL injections by escaping the user-defined tokens
            cmd.CommandText = string.Format(CreateColumnMasterKeyTemplate,
                    cmkName.Replace("]", "]]"), providerName.Replace(@"'", @"''"), keyId.Replace(@"'", @"''"));

            cmd.ExecuteNonQuery();
        }

        [SuppressMessage("Microsoft.Security", "CA2100", Justification = "The SqlCommand text is issuing a DDL statement that requires to use only literals (no parameterization is possible). The user input is being escaped.", Scope = "method")]
        static void CreateTable(SqlConnection connection, string cekName)
        {
            SqlCommand cmd = connection.CreateCommand();

            // Prevent SQL injections by escaping the user-defined tokens
            cmd.CommandText = string.Format(CreateTableTemplate,
                    cekName.Replace("]", "]]"));

            cmd.ExecuteNonQuery();
        }

        [SuppressMessage("Microsoft.Security", "CA2100", Justification = "The SqlCommand text is issuing a DDL statement that requires to use only literals (no parameterization is possible). The user input is being escaped.", Scope = "method")]
        static void CreateColumnEncryptionKey(SqlConnection connection, string cekName, string cmkName, string keyId, ref SqlColumnEncryptionAzureKeyVaultProvider akvprov)
        {
            // Generate the raw bytes that will be used as a key by using a CSPRNG
            byte[] cekRawValue = new byte[32];
            var provider = new RNGCryptoServiceProvider();
            provider.GetBytes(cekRawValue);

            // Encrypt the newly created random key using the AKV provider
            var cekEncryptedValue = akvprov.EncryptColumnEncryptionKey(keyId, @"RSA_OAEP", cekRawValue);

            var cmd = connection.CreateCommand();

            // Prevent SQL injections by escaping the user-defined tokens
            cmd.CommandText = string.Format(CreateColumnEncryptionKeyTemplate,
                cekName.Replace("]", "]]"), cmkName.Replace("]", "]]"), BytesToHex(cekEncryptedValue));

            cmd.ExecuteNonQuery();
        }

        static bool ParseCommandLineOptions(string[] args)
        {
            bool appClientIdSet = false;
            bool appKeySet = false;
            bool connStrSet = false;
            bool keyIdSet = false;
            bool operationSet = false;

            for (int i = 0; i < args.Length - 1; i++)
            {
                if(args[i].Equals(AppClientIdToken, StringComparison.CurrentCultureIgnoreCase))
                {
                    i++;
                    _applicationClientId = args[i];
                    appClientIdSet = true;
                }
                else if (args[i].Equals(AppKey, StringComparison.CurrentCultureIgnoreCase))
                {
                    i++;
                    _applicationKey = args[i];
                    appKeySet = true;
                }
                else if (args[i].Equals(KeyId, StringComparison.CurrentCultureIgnoreCase))
                {
                    i++;
                    _keyId = args[i];
                    keyIdSet = true;
                }
                else if (args[i].Equals(Token, StringComparison.CurrentCultureIgnoreCase))
                {
                    i++;
                    _connectionString = args[i];
                    connStrSet = true;
                }
                else if (args[i].Equals(Operation, StringComparison.CurrentCultureIgnoreCase))
                {
                    i++;
                    if (args[i].Equals(OperationCreateKeyObjects, StringComparison.CurrentCultureIgnoreCase))
                    {
                        _runSetupOnly = true;
                    }
                    else if (args[i].Equals(OperationDataAccess, StringComparison.CurrentCultureIgnoreCase))
                    {
                        _runSetupOnly = false;
                    }
                    else
                    {
                        return false;
                    }
                    operationSet = true;
                }
                else
                {
                    return false;
                }                
            }
            return (keyIdSet && connStrSet && appKeySet && appClientIdSet && operationSet);
        }

        static void PrintUsage()
        {
            Console.WriteLine(@"Usage: SqlKeyVaultSampleApp {0} <application client ID> {1} <application client Key> {2} <connection string> {3} <Azure Key Vault Key ID> {4} <{5}|{6}>",
                AppClientIdToken, AppKey, Token, KeyId, Operation,
                OperationCreateKeyObjects, OperationDataAccess);
        }

        static void Main(string[] args)
        {
            if(!ParseCommandLineOptions(args))
            {
                PrintUsage();
                return;
            }
            
            using (var connection = new SqlConnection(_connectionString))
            {
                try
                {
                    // This is the name we will use for our column master key.
                    // It should be used when creating the column master key object in SQL Server,
                    // and when registering the custom provider instance to SqlConnection.
                    //
                    const string customAkvProviderName = @"AZURE_KEY_VAULT_PROVIDER";

                    connection.Open();

                    // Instanciate our custom AKV column master key provider.
                    // We will use the GetToken function we implemented above as the callback function to authenticate to AKV
                    //
                    var keyVaultProvider = new SqlColumnEncryptionAzureKeyVaultProvider(GetToken);

                    if (_runSetupOnly)
                    {
                        string cmkName = "XPT_CMK1";
                        string cekName = "XPT_CEK1";

                        Console.WriteLine(@"Creating column master key...");
                        CreateColumnMasterKey(connection, cmkName, customAkvProviderName, _keyId);

                        Console.WriteLine(@"Creating column encryption key...");
                        CreateColumnEncryptionKey(connection, cekName, cmkName, _keyId, ref keyVaultProvider);

                        Console.WriteLine(@"Creating table...");
                        CreateTable(connection, cekName);
                    }
                    else
                    {
                        // In case we will access data, we need to register the instance of our custom provider to SqlConnection
                        // 
                        Dictionary<string, SqlColumnEncryptionKeyStoreProvider> providers = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();

                        // "AZURE_KEY_VAULT_PROVIDER" is the name of the provider. It must match the string we used when we created the column master key
                        providers.Add(customAkvProviderName, keyVaultProvider);
                        SqlConnection.RegisterColumnEncryptionKeyStoreProviders(providers);

                        Console.WriteLine(@"Inserting data...");
                        Random rand = new Random();
                        for (int i = 0; i < 10; i++)
                        {
                            string val = string.Format(@"{0:d3}-{1:d2}-{2:d4}", rand.Next(0, 1000), rand.Next(0, 100), rand.Next(0, 10000));
                            InsertData(connection, val);
                        }
                        Console.WriteLine(@"Selecting data...");
                        SelectData(connection);
                    }
                    Console.WriteLine(@"[done]");
                }
                finally
                {
                    if (connection.State == System.Data.ConnectionState.Open)
                    {
                        connection.Close();
                    }
                }
            }
        }
    }
}

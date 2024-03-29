using System.Net;
using System.Text;
using DatingApp.API.Data;
using DatingApp.API.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<DataContext>(x =>
                x.UseSqlServer(Configuration.GetConnectionString("SQLServerConnection")));
            services.AddScoped<IAuthRepository, AuthRepository>();
            services.AddCors();
            services.AddControllers();
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(AddJwtOptions);
        }

        // passed as group method, delegate
        private void AddJwtOptions(JwtBearerOptions options)
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.ASCII.GetBytes(Configuration.GetSection("AppSettings:Token").Value)
                    ),
                ValidateIssuer = false,
                ValidateAudience = false
            };
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                AddCustomExceptionHandler(app);
            }

            app.UseRouting();

            // Cors after UseRouting and before UseEndpoints
            app.UseCors(x => x.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            //place app.UseAuthentication() before app.UseAuthorization()
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }

        private static void AddCustomExceptionHandler(IApplicationBuilder app)
        {
            app.UseExceptionHandler(builder =>
            {
                builder.Run(async context =>
                {
                    context.Response.StatusCode = (int) HttpStatusCode.InternalServerError;
                    var error = context.Features.Get<IExceptionHandlerFeature>();
                    if (error != null)
                    {
                        context.Response.AddApplicationError(error.Error.Message);
                        await context.Response.WriteAsync(error.Error.Message);
                    }
                });
            });
        }
    }
}
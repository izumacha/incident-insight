using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentInsight.Web.Migrations
{
    /// <inheritdoc />
    public partial class AddMaxLengthToCauseCategoryDescription : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 本体が空なのは意図どおり。既定プロバイダの SQLite は TEXT 列に長さ制約を持たないため、
            // CauseCategory.Description へ [MaxLength(500)] を付けても発行すべき DDL が無い。
            // それでもマイグレーションを起こすのは、モデルスナップショットに上限を記録して
            // 次回以降の差分計算を正しくするため(SQL Server / PostgreSQL 向けに Migrations/ を
            // 再生成したときは、この上限が nvarchar(500) / varchar(500) として反映される)。
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Up と同じ理由で戻す DDL も無い(SQLite には長さ制約が存在しない)。
        }
    }
}

/*
@File : dateUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 16:56
*/

package util

import (
	"fmt"
	"strconv"
	"time"
)

/*
	获得指定时间戳的整数年月
 */
func TS2YearAndMonth(ts int64) (year int, month int) {
	year = time.Unix(ts, 0).Year()
	month, _ = strconv.Atoi(time.Unix(ts, 0).Format("1"))
	return
}

/*
	总月份个数
 */
func GetMonthNums(sym string, eym string) int64 {
	dateInt, _:= strconv.Atoi(sym)
	dateEndInt, _:= strconv.Atoi(eym)
	sy := dateInt / 100
	sm := dateInt % 100
	ey := dateEndInt / 100
	em := dateEndInt % 100
	return int64((ey - sy) * 12 - sm + em + 1)
}

/*
	中文月份
 */
func GetChineseMonth(ym string) string {
	dateInt, _:= strconv.Atoi(ym)
	sy := dateInt / 100
	sm := dateInt % 100
	return fmt.Sprintf("%d年%d月", sy, sm)
}

/*
	获得指定年月间的年月表，通过指定年月区间，包括截止月
 */
func GetSpecYMsByYM(sy int, sm int, ey int, em int) ([]string, int) {
	ymNum := (ey - sy) * 12 - sm + em + 1	// 总月份个数
	var yms = make([]string, 0)
	if sy == ey {							// 同一年
		for m := sm; m <= em; m++ {
			ym := fmt.Sprintf("%04d%02d", sy, m)
			yms = append(yms, ym)
		}
	} else {								// 不同年
		// 起始年
		for m := sm; m <= 12; m++ {
			ym := fmt.Sprintf("%04d%02d", sy, m)
			yms = append(yms, ym)
		}
		// 中间年
		for y := sy + 1; y < ey; y++ {
			for m := 1; m <= 12; m++ {
				ym := fmt.Sprintf("%04d%02d", y, m)
				yms = append(yms, ym)
			}
		}
		// 截止年
		for m := 1; m <= em; m++ {
			ym := fmt.Sprintf("%04d%02d", ey, m)
			yms = append(yms, ym)
		}
	}
	return yms, ymNum
}

/*
	获得指定年月间的年月表，通过指定时间戳中的年月区间，包括截止月
 */
func GetSpecYMsByTS(tsStart int64, tsEnd int64) ([]string, int) {
	sy, sm := TS2YearAndMonth(tsStart)		// 起始年月
	ey, em := TS2YearAndMonth(tsEnd)		// 截止年月
	ymNum := (ey - sy) * 12 - sm + em + 1	// 总月份个数
	var yms = make([]string, 0)
	if sy == ey {							// 同一年
		for m := sm; m <= em; m++ {
			ym := fmt.Sprintf("%04d%02d", sy, m)
			yms = append(yms, ym)
		}
	} else {								// 不同年
		// 起始年
		for m := sm; m <= 12; m++ {
			ym := fmt.Sprintf("%04d%02d", sy, m)
			yms = append(yms, ym)
		}
		// 中间年
		for y := sy + 1; y < ey; y++ {
			for m := 1; m <= 12; m++ {
				ym := fmt.Sprintf("%04d%02d", y, m)
				yms = append(yms, ym)
			}
		}
		// 截止年
		for m := 1; m <= em; m++ {
			ym := fmt.Sprintf("%04d%02d", ey, m)
			yms = append(yms, ym)
		}
	}
	return yms, ymNum
}

/*
	花费时间
 */
func CostTime(tm time.Time) string {
	timeNow := time.Now()
	days := timeNow.Sub(tm) / (24 * time.Hour)
	hours := timeNow.Sub(tm) % (24 * time.Hour) / time.Hour
	minutes := timeNow.Sub(tm) % (24 * time.Hour) % time.Hour / time.Minute
	seconds := timeNow.Sub(tm) % (24 * time.Hour) % time.Hour % time.Minute / time.Second

	return fmt.Sprintf("%02dd%02dh%02dm%02ds", days, hours, minutes, seconds)
}
